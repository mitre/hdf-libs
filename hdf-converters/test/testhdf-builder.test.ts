import { describe, it } from 'vitest';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { expectValidResults } from './helpers/expectValidHdf.js';

describe('@mitre/hdf-schema/testhdf builder', () => {
  it('defaults produce schema-valid HDF', () => {
    expectValidResults(testhdf.results(testhdf.req('X')));
  });

  it('options produce schema-valid HDF', () => {
    expectValidResults(
      testhdf.results(
        testhdf.req('AC-1', {
          severity: 'high',
          impact: 0.7,
          status: 'failed',
          tags: { nist: ['AC-1'] },
          cwe: ['CWE-79'],
        }),
        testhdf.req('AC-2', { status: 'passed', addDesc: [['check', 'the check text']] }),
      ),
    );
  });

  it('multi-baseline doc is schema-valid', () => {
    expectValidResults(testhdf.doc(testhdf.baseline('b1', testhdf.req('X')), testhdf.baseline('b2', testhdf.req('Y'))));
  });
});
