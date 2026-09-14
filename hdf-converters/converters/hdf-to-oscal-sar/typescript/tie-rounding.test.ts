import { describe, it, expect } from 'vitest';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { convertHdfToOscalSar } from './converter.js';

// The Go peer asserts this same string on the same shape. Impact 0.25 ties at
// one decimal, where toFixed rounds away from zero and Go's fmt rounds to even.
// Built with the testhdf builder rather than a committed fixture: the document
// asserts nothing about real-world data shape, only about how one number renders.
function tieDocument(): string {
  return JSON.stringify(
    testhdf.doc(
      testhdf.baseline(
        'tie',
        testhdf.req('AC-1', {
          impact: 0.25,
          tags: { nist: ['AC-1'] },
          desc: 'impact 0.25 ties at one decimal',
          status: 'failed',
        }),
      ),
    ),
  );
}

describe('hdf-to-oscal-sar renders exact ties the way Go now does', () => {
  it('rounds impact 0.25 to 0.3 at one decimal', async () => {
    const out = await convertHdfToOscalSar(tieDocument());
    expect(out).toContain('Impact: 0.3 (');
    expect(out).not.toContain('Impact: 0.2 (');
  });
});
