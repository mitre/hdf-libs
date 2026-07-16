import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { countXmlElements } from '../../../shared/typescript/anchor.js';
import { convertHdfToXccdf } from './converter.js';

// Export-side ground-truth anchor: XCCDF is a SINGLE-benchmark format, so
// hdf-to-xccdf emits one benchmark from baselines[0] only, with one <rule-result>
// per requirement in that baseline. The emitted <rule-result> count must equal
// the FIRST baseline's requirement count (the documented single-benchmark
// collapse — distinct from the whole-document total). Mirrors Go.
describe('hdf-to-xccdf output-count anchor', () => {
  it('emits one <rule-result> per requirement in the first (only exported) baseline', () => {
    const input = results.inspecMultilayered.read();
    const baselines = (JSON.parse(input) as { baselines?: Array<{ requirements?: unknown[] }> }).baselines ?? [];
    expect(baselines.length).toBeGreaterThan(0);
    const want = baselines[0]!.requirements?.length ?? 0;
    expect(want).toBeGreaterThan(1);

    const got = countXmlElements(convertHdfToXccdf(input), 'rule-result');
    expect(got, 'one <rule-result> per first-baseline requirement').toBe(want);
  });
});
